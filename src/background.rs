use crate::base::*;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::ERROR_CODE_MISMATCH;
use crate::ERROR_CODE_PARAM;
use crate::ERROR_CODE_SERVER_ERROR;
use crate::ERROR_CODE_TIMEOUT;
use edamame_core::api::api_agentic::*;
use edamame_core::api::api_core::*;
use edamame_core::api::api_fim::*;
use edamame_core::api::api_flodbadd::*;
use edamame_core::api::api_metrics::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_history::*;
use edamame_core::api::api_score_threats::*;
use edamame_core::api::api_trust::*;
use edamame_core::api::api_visibility::*;
use flodbadd::blacklists::BlacklistsJSON;
use std::thread::sleep;
use std::time::Duration;
use tracing::{error, info, warn};

pub fn background_get_sessions(
    zeek_format: bool,
    local_traffic: bool,
    fail_on_anomalous: bool,
    fail_on_blacklist: bool,
    fail_on_whitelisted: bool,
) -> i32 {
    let sessions = match rpc_get_lan_sessions(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting LAN sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    // Filter and display sessions (normal mode)
    background_display_sessions(sessions.sessions, zeek_format, local_traffic, false);

    // Determine exit code based on checks
    let mut exit_code = 0;

    // Always check whitelist conformance
    if fail_on_whitelisted {
        let whitelist_conformance = match rpc_get_whitelist_conformance(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(conformance) => conformance,
            Err(e) => {
                eprintln!("Error getting whitelist conformance: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };

        if !whitelist_conformance {
            eprintln!("Non-conforming sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    // Check for anomalous sessions if requested
    if fail_on_anomalous {
        let anomalous_status = match rpc_get_anomalous_status(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error checking anomalous session status: {}", e);
                false
            }
        };

        if anomalous_status {
            eprintln!("Anomalous sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    // Check for blacklisted sessions if requested
    if fail_on_blacklist {
        let blacklisted_status = match rpc_get_blacklisted_status(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error checking blacklisted session status: {}", e);
                false
            }
        };

        if blacklisted_status {
            eprintln!("Blacklisted sessions detected");
            exit_code = ERROR_CODE_MISMATCH;
        }
    }

    return exit_code;
}

pub fn background_display_sessions(
    sessions: Vec<SessionInfoAPI>,
    zeek_format: bool,
    local_traffic: bool,
    exceptions_only: bool,
) {
    // Get all sessions first
    let mut filtered_sessions = sessions;

    // If we only want exceptions, find the exceptions
    if exceptions_only {
        // Extract the sessions with status that aren't "Conforming"
        filtered_sessions = filtered_sessions
            .into_iter()
            .filter(|session| {
                session.is_whitelisted
                    != edamame_core::api::api_flodbadd::WhiteListStateAPI::Conforming
            })
            .collect::<Vec<_>>();
    }

    // Filter out local traffic if requested
    if !local_traffic {
        filtered_sessions = filter_global_sessions(filtered_sessions);
    }

    // Format the connections and display them
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(filtered_sessions)
    } else {
        format_sessions_log(filtered_sessions)
    };

    // Display the sessions
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }
}

pub fn background_get_exceptions(zeek_format: bool, local_traffic: bool) -> i32 {
    let sessions = match rpc_get_lan_sessions(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting LAN sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    // Display only exceptions
    background_display_sessions(sessions.sessions, zeek_format, local_traffic, true);

    return 0;
}

pub fn background_get_threats_info() -> i32 {
    match rpc_get_score(
        false,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(score) => {
            println!(
                "Threat model name: {}, date: {}, signature: {}",
                score.model_name, score.model_date, score.model_signature
            );
            0
        }
        Err(e) => {
            eprintln!("Error getting threats info: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_get_status() -> i32 {
    use std::io::{self, Write};

    // Helper to write to stdout, ignoring broken pipe errors (when output is piped)
    fn write_stdout(s: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        match writeln!(handle, "{}", s) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(e),
        }
    }

    match rpc_get_connection(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            let _ = write_stdout("Connection status:");
            let _ = write_stdout(&status.to_string());

            // Also display agentic status if available
            match rpc_agentic_get_auto_processing_status(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(agentic_status) => {
                    let _ = write_stdout("AI Assistant:");
                    let mode_str = match agentic_status.mode {
                        0 => "disabled",
                        1 => "analyze",
                        2 => "auto",
                        _ => "unknown",
                    };
                    let _ = write_stdout(&format!("  - Mode: {}", mode_str));
                    let _ =
                        write_stdout(&format!("  - Interval: {}s", agentic_status.interval_secs));
                    let _ = write_stdout(&format!(
                        "  - Enabled: {}",
                        if agentic_status.enabled { "yes" } else { "no" }
                    ));
                    if let Some(ref last_run) = agentic_status.last_run {
                        let _ = write_stdout(&format!("  - Last run: {}", last_run));
                    }
                    if let Some(ref next_run) = agentic_status.next_run {
                        let _ = write_stdout(&format!("  - Next run: {}", next_run));
                    }
                }
                Err(_) => {
                    // Agentic status not available (might not be running in background mode)
                }
            }

            0
        }
        Err(e) => {
            eprintln!("Error getting connection status: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_get_last_report_signature() -> i32 {
    let signature = match rpc_get_last_report_signature(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(signature) => signature,
        Err(e) => {
            eprintln!("Error getting last reported signature: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };
    println!("{}", signature);
    0
}

pub fn background_get_device_info() -> i32 {
    let info = match rpc_get_device_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error getting device information: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };
    println!("Device information from the background process:");
    println!("{}", info);
    0
}

pub fn background_wait_for_connection(timeout: u64) -> i32 {
    // Display device and system info
    background_get_device_info();
    base_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;

    let mut connection_status = ConnectionStatusAPI {
        connected_domain: "".to_string(),
        connected_user: "".to_string(),
        pin: "".to_string(),
        is_success: false,
        is_connected: false,
        is_success_pin: false,
        is_outdated_backend: false,
        is_outdated_threats: false,
        last_network_activity: "".to_string(),
        last_report_time: "".to_string(),
        last_report_signature: "".to_string(),
        backend_error_code: "".to_string(),
        backend_error_reason: "".to_string(),
        is_online: false,
    };

    // Wait until the daemon reports that it is connected, or until we time out
    while !connection_status.is_connected && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;

        connection_status = match rpc_get_connection(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("Error getting connection status: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };

        // The backend error code won't reflect an actual error until communication with the backend occur, i.e. the connection is established
        if connection_status.is_connected && connection_status.backend_error_code != "None" {
            eprintln!(
                "Error attempting to connect to domain: {}, {}",
                connection_status.backend_error_code, connection_status.backend_error_reason
            );
            return ERROR_CODE_PARAM;
        }

        println!(
            "Waiting for score computation and reporting to complete... (connected: {}, network activity: {}, report signature: {})",
            connection_status.is_connected,
            connection_status.last_network_activity,
            connection_status.last_report_signature
        );
    }

    if timeout == 0 || !connection_status.is_connected {
        eprintln!("Timeout waiting for background process to connect to domain...");
        return ERROR_CODE_TIMEOUT;
    } else {
        println!(
            "Connection successful with domain {} and user {} (connected: {}, network activity: {})",
            connection_status.connected_domain,
            connection_status.connected_user,
            connection_status.is_connected,
            connection_status.last_network_activity
        );

        // Print the score results
        let score = match rpc_get_score(
            false,
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(score) => score,
            Err(e) => {
                eprintln!("Error getting score: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };
        let url = get_threats_url().to_string();
        // Pretty print the final score with important details
        println!("Security Score summary:");
        println!("{}", score);
        println!("Model URL: {}", url);

        // Print the lanscan results
        let devices = match rpc_get_lanscan(
            false,
            false,
            false,
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(devices) => devices,
            Err(e) => {
                eprintln!("Error getting LAN devices: {}", e);
                return ERROR_CODE_SERVER_ERROR;
            }
        };
        println!("LAN scan completed at: {}", devices.last_scan);
        println!("{}", devices);
    }
    0
}

pub fn background_stop() -> i32 {
    match rpc_terminate(
        true,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error terminating background process: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
    0
}

pub fn background_get_history() -> i32 {
    match rpc_get_history(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(history) => {
            println!("History: {:#?}", history);
            0
        }
        Err(e) => {
            eprintln!("Error getting history: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_create_custom_whitelists_with_list() -> (String, i32) {
    match rpc_create_custom_whitelists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            if whitelists.is_empty() {
                eprintln!("Failed to create custom whitelists");
                return (String::new(), ERROR_CODE_SERVER_ERROR);
            } else {
                // The whitelist is a String represent a JSON object
                // We need to parse it and print it pretty
                let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Error parsing whitelist JSON: {}", e);
                        return (String::new(), ERROR_CODE_SERVER_ERROR);
                    }
                };
                let pretty_json = match serde_json::to_string_pretty(&json_value) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Error formatting whitelist JSON: {}", e);
                        return (String::new(), ERROR_CODE_SERVER_ERROR);
                    }
                };
                println!("{}", pretty_json);
                return (pretty_json, 0);
            }
        }
        Err(e) => {
            eprintln!("Error creating custom whitelists: {}", e);
            return (String::new(), ERROR_CODE_SERVER_ERROR);
        }
    }
}

pub fn background_create_custom_whitelists() -> i32 {
    let (_, exit_code) = background_create_custom_whitelists_with_list();
    exit_code
}

/// Create custom whitelists with process information included.
/// This provides stricter matching (connections must come from the same process).
pub fn background_create_custom_whitelists_with_process() -> i32 {
    match rpc_create_custom_whitelists_with_process(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            if whitelists.is_empty() {
                eprintln!("Failed to create custom whitelists with process");
                return ERROR_CODE_SERVER_ERROR;
            } else {
                let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Error parsing whitelist JSON: {}", e);
                        return ERROR_CODE_SERVER_ERROR;
                    }
                };
                let pretty_json = match serde_json::to_string_pretty(&json_value) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Error formatting whitelist JSON: {}", e);
                        return ERROR_CODE_SERVER_ERROR;
                    }
                };
                println!("{}", pretty_json);
                return 0;
            }
        }
        Err(e) => {
            eprintln!("Error creating custom whitelists with process: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    }
}

pub fn background_set_custom_whitelists(whitelist_json: String) -> i32 {
    match rpc_set_custom_whitelists(
        whitelist_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Error setting custom whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_create_and_set_custom_whitelists() -> i32 {
    let (whitelist_json, exit_code) = background_create_custom_whitelists_with_list();
    if exit_code != 0 {
        return exit_code;
    }
    background_set_custom_whitelists(whitelist_json)
}

pub fn background_get_score() -> i32 {
    match rpc_get_score(
        false,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(score) => {
            println!("Security Score summary:");
            println!("{}", score);

            // Get threats URL
            match rpc_get_threats_url(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(url) => println!("Model URL: {}", url),
                Err(_) => (), // Ignore error if we can't get the URL
            }
            0
        }
        Err(e) => {
            eprintln!("Error getting score: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to display anomalous sessions
pub fn background_get_anomalous_sessions(zeek_format: bool) -> i32 {
    // Get anomalous sessions
    let anomalous_sessions = match rpc_get_anomalous_sessions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting anomalous sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    if anomalous_sessions.is_empty() {
        return 0;
    }

    // Format and display sessions
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(anomalous_sessions)
    } else {
        format_sessions_log(anomalous_sessions)
    };
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }

    return 0; // Always return 0 on success, even if sessions are found
}

// Function to display blacklisted sessions
pub fn background_get_blacklisted_sessions(zeek_format: bool) -> i32 {
    // Get blacklisted sessions
    let blacklisted_sessions = match rpc_get_blacklisted_sessions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(sessions) => sessions,
        Err(e) => {
            eprintln!("Error getting blacklisted sessions: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    if blacklisted_sessions.is_empty() {
        return 0;
    }

    // Format and display sessions
    let formatted_sessions = if zeek_format {
        format_sessions_zeek(blacklisted_sessions)
    } else {
        format_sessions_log(blacklisted_sessions)
    };
    for session in formatted_sessions.iter() {
        println!("{}", session);
    }

    return 0; // Always return 0 on success, even if sessions are found
}

fn validate_custom_blacklists_json(blacklist_json: &str) -> Result<(), String> {
    // Empty JSON is a supported "reset to default" signal.
    if blacklist_json.trim().is_empty() {
        return Ok(());
    }

    // Parse the exact schema used by flodbadd, so we fail fast with a useful
    // error message instead of sending malformed payloads over RPC.
    serde_json::from_str::<BlacklistsJSON>(blacklist_json)
        .map(|_| ())
        .map_err(|e| format!("Invalid custom blacklist JSON (schema mismatch): {e}"))
}

pub fn background_set_custom_blacklists(blacklist_json: String) -> i32 {
    if let Err(msg) = validate_custom_blacklists_json(&blacklist_json) {
        eprintln!("Error setting custom blacklists: {msg}");
        return ERROR_CODE_PARAM;
    }

    match rpc_set_custom_blacklists(
        blacklist_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            println!("Custom blacklists set successfully.");
            0
        }
        Err(e) => {
            eprintln!("Error setting custom blacklists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve blacklists
pub fn background_get_blacklists() -> i32 {
    match rpc_get_blacklists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(blacklists) => {
            // The list is a String represent a JSON object
            // We need to parse it and print it pretty
            let json_value: serde_json::Value = match serde_json::from_str(&blacklists) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error parsing blacklist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            let pretty_json = match serde_json::to_string_pretty(&json_value) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error formatting blacklist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            println!("{}", pretty_json);
            0
        }
        Err(e) => {
            eprintln!("Error getting blacklists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve whitelists
pub fn background_get_whitelists() -> i32 {
    match rpc_get_whitelists(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(whitelists) => {
            // The list is a String represent a JSON object
            // We need to parse it and print it pretty
            let json_value: serde_json::Value = match serde_json::from_str(&whitelists) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error parsing whitelist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            let pretty_json = match serde_json::to_string_pretty(&json_value) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error formatting whitelist JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            println!("{}", pretty_json);
            0
        }
        Err(e) => {
            eprintln!("Error getting whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to retrieve whitelist name
pub fn background_get_whitelist_name() -> i32 {
    match rpc_get_whitelist_name(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(name) => {
            println!("{}", name);
            0
        }
        Err(e) => {
            eprintln!("Error getting whitelist name: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// Function to augment custom whitelists from the background process
pub fn background_augment_custom_whitelists() -> i32 {
    match rpc_augment_custom_whitelists_info(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok((whitelist_json, percent_changed)) => {
            if whitelist_json.is_empty() {
                eprintln!("Failed to augment custom whitelists");
                return ERROR_CODE_SERVER_ERROR;
            }

            // Informational: report % of changes to stderr so stdout remains JSON-only
            eprintln!("Percent of changes: {:.2}", percent_changed);

            match serde_json::from_str::<serde_json::Value>(&whitelist_json) {
                Ok(json_value) => {
                    match serde_json::to_string_pretty(&json_value) {
                        Ok(pretty_json) => println!("{}", pretty_json),
                        Err(_) => println!("{}", whitelist_json),
                    }
                    0
                }
                Err(e) => {
                    eprintln!("Error parsing augmented whitelist JSON: {}", e);
                    ERROR_CODE_PARAM
                }
            }
        }
        Err(e) => {
            eprintln!("Error augmenting custom whitelists: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Configure notification channels for the EDAMAME Portal provider path.
/// The EDAMAME API key is already set; this merges Slack/Telegram one-way
/// notification fields into the existing config by calling
/// `agentic_set_llm_config` with `provider="internal"` (the merge logic in
/// `api_agentic.rs` preserves OAuth/API-key state for the internal provider).
fn configure_edamame_notifications() {
    use edamame_core::api::api_agentic::*;

    let slack_bot_token = std::env::var("EDAMAME_AGENTIC_SLACK_BOT_TOKEN")
        .or_else(|_| std::env::var("EDAMAME_AGENTIC_WEBHOOK_ACTIONS_TOKEN"))
        .unwrap_or_default();
    let slack_actions_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL").unwrap_or_default();
    let slack_escalations_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL").unwrap_or_default();

    let telegram_bot_token = std::env::var("EDAMAME_TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let telegram_chat_id = std::env::var("EDAMAME_TELEGRAM_CHAT_ID").unwrap_or_default();

    if slack_bot_token.is_empty()
        && (!slack_actions_channel.is_empty() || !slack_escalations_channel.is_empty())
    {
        warn!("Slack notifications requested but EDAMAME_AGENTIC_SLACK_BOT_TOKEN is missing");
    }

    if !slack_actions_channel.is_empty() {
        info!(
            "AI Assistant Slack actions channel configured: {}",
            slack_actions_channel
        );
    }
    if !slack_escalations_channel.is_empty() {
        info!(
            "AI Assistant Slack escalations channel configured: {}",
            slack_escalations_channel
        );
    }
    if !telegram_bot_token.is_empty() && !telegram_chat_id.is_empty() {
        info!(
            "Telegram notifications configured (chat_id: {})",
            telegram_chat_id
        );
    }

    if !slack_bot_token.is_empty() || !telegram_bot_token.is_empty() {
        let slack_enabled = !slack_bot_token.is_empty();
        let telegram_enabled = !telegram_bot_token.is_empty();
        let export_to_portal = std::env::var("EDAMAME_EXPORT_TO_PORTAL")
            .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
            .unwrap_or(false);
        if agentic_set_llm_config(
            "internal".to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            slack_bot_token,
            slack_actions_channel,
            slack_escalations_channel,
            telegram_bot_token,
            telegram_chat_id,
            slack_enabled,
            telegram_enabled,
            export_to_portal,
        ) {
            info!("Notification channels configured");
        } else {
            warn!("Failed to configure notification channels");
        }
    }
}

/// Configure Telegram interactive (bidirectional) mode: inline buttons for
/// execute/undo/dismiss/restore actions directly from the Telegram chat.
/// Called after both the LLM provider and one-way notification channels are set.
fn configure_telegram_interactive() {
    use edamame_core::api::api_agentic::*;

    let enabled = std::env::var("EDAMAME_TELEGRAM_INTERACTIVE_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !enabled {
        return;
    }

    let allowed_user_ids: Vec<i64> = std::env::var("EDAMAME_TELEGRAM_ALLOWED_USER_IDS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<i64>().ok())
        .collect();

    if allowed_user_ids.is_empty() {
        warn!("Telegram interactive mode enabled but EDAMAME_TELEGRAM_ALLOWED_USER_IDS is empty -- no users will be authorized");
    }

    if agentic_set_telegram_interactive_config(enabled, allowed_user_ids.clone()) {
        info!(
            "Telegram interactive mode enabled ({} authorized user(s))",
            allowed_user_ids.len()
        );
    } else {
        warn!("Failed to configure Telegram interactive mode");
    }
}

/// Configure agentic LLM provider for background process
#[allow(unused_variables)]
pub fn background_configure_agentic(provider: String) {
    use edamame_core::api::api_agentic::*;

    info!("Configuring AI Assistant provider: {}", provider);

    // Unified API key handling through EDAMAME_LLM_API_KEY for all providers
    let api_key = std::env::var("EDAMAME_LLM_API_KEY").unwrap_or_default();

    // Handle EDAMAME Portal LLM
    if provider == "edamame" {
        if api_key.is_empty() {
            error!("EDAMAME_LLM_API_KEY environment variable is required for provider 'edamame'");
            error!("Get your API key at https://portal.edamame.tech/api-keys");
            return;
        }

        if !api_key.starts_with("edm_") && !api_key.starts_with("edak_") {
            warn!("EDAMAME Portal API key should start with 'edm_' or 'edak_' prefix");
        }

        // Set the EDAMAME API key for headless authentication
        if agentic_set_edamame_api_key(api_key) {
            info!("AI Assistant configured with EDAMAME Portal LLM");
            // Trigger device registration with the Portal by querying the subscription/plan
            // endpoint. This mirrors the app's init sequence (agenticGetSubscriptionStatus
            // after OAuth sign-in) and ensures the device_id is known to the Portal before
            // any agentic_analysis calls are made.
            let status = agentic_get_subscription_status();
            info!(
                "Portal subscription: plan={}, usage={}",
                status.plan_name, status.usage
            );
        } else {
            error!("Failed to set EDAMAME API key");
        }

        configure_edamame_notifications();
        configure_telegram_interactive();
        return;
    }

    // Handle BYOLLM providers (claude, openai, ollama)
    let model = std::env::var("EDAMAME_LLM_MODEL").unwrap_or_else(|_| match provider.as_str() {
        "claude" => "claude-haiku-4-5-20251001".to_string(),
        "openai" => "gpt-5-mini-2025-08-07".to_string(),
        "ollama" => "llama4".to_string(),
        _ => String::new(),
    });
    let base_url = std::env::var("EDAMAME_LLM_BASE_URL").unwrap_or_default();
    let slack_bot_token = std::env::var("EDAMAME_AGENTIC_SLACK_BOT_TOKEN")
        .or_else(|_| std::env::var("EDAMAME_AGENTIC_WEBHOOK_ACTIONS_TOKEN"))
        .unwrap_or_default();
    let slack_actions_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ACTIONS_CHANNEL").unwrap_or_default();
    let slack_escalations_channel =
        std::env::var("EDAMAME_AGENTIC_SLACK_ESCALATIONS_CHANNEL").unwrap_or_default();

    let telegram_bot_token = std::env::var("EDAMAME_TELEGRAM_BOT_TOKEN").unwrap_or_default();
    let telegram_chat_id = std::env::var("EDAMAME_TELEGRAM_CHAT_ID").unwrap_or_default();

    // MCP PSK not needed for background mode (no external AI clients)
    let mcp_psk = String::new();

    let slack_enabled = !slack_bot_token.is_empty();
    let telegram_enabled = !telegram_bot_token.is_empty();
    let export_to_portal = std::env::var("EDAMAME_EXPORT_TO_PORTAL")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);
    if agentic_set_llm_config(
        provider.clone(),
        api_key.clone(),
        model.clone(),
        base_url,
        mcp_psk,
        slack_bot_token,
        slack_actions_channel,
        slack_escalations_channel,
        telegram_bot_token,
        telegram_chat_id,
        slack_enabled,
        telegram_enabled,
        export_to_portal,
    ) {
        info!("AI Assistant configured: {} / {}", provider, model);
    } else {
        error!("Failed to configure AI Assistant. Check EDAMAME_LLM_API_KEY environment variable.");
    }

    configure_telegram_interactive();
}

// ============================================================================
// MCP Server Control (for headless/daemon mode)
// ============================================================================

pub fn background_mcp_generate_psk() -> i32 {
    let psk = mcp_generate_psk();
    println!("{}", psk);
    println!("# Save this PSK securely - it's required for MCP client authentication");
    0
}

pub fn background_mcp_start(port: u16, psk: Option<String>, all_interfaces: bool) -> i32 {
    use edamame_core::api::api_agentic::rpc_mcp_start_server;

    // Use provided PSK or generate new one
    let actual_psk = psk.unwrap_or_else(|| {
        let generated = mcp_generate_psk();
        println!("# Generated new PSK: {}", generated);
        println!("# Save this PSK - you'll need it to connect MCP clients");
        generated
    });

    if actual_psk.len() < 32 {
        eprintln!("Error: PSK must be at least 32 characters");
        eprintln!("Generate one with: edamame_posture mcp-generate-psk");
        return ERROR_CODE_PARAM;
    }

    match rpc_mcp_start_server(
        port,
        actual_psk.clone(),
        false,
        all_interfaces,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                let bind_addr = if all_interfaces {
                    "<your-ip-address>"
                } else {
                    "127.0.0.1"
                };
                println!("[OK] MCP server started successfully");
                println!("   Port: {}", json["port"]);
                println!("   URL: {}", json["url"].as_str().unwrap_or(""));
                println!("   PSK: {}", actual_psk);
                if all_interfaces {
                    println!("\n[WARN] Warning: Server is listening on ALL network interfaces");
                    println!(
                        "   Accessible from your local network - ensure your network is secure!"
                    );
                }
                println!("\nClaude Desktop config:");
                println!(
                    r#"{{
  "mcpServers": {{
    "edamame": {{
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://{}:{}/mcp",
        "--header",
        "Authorization: Bearer {}"
      ]
    }}
  }}
}}"#,
                    bind_addr, port, actual_psk
                );
                0
            } else {
                eprintln!(
                    "Failed to start MCP server: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error starting MCP server: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_mcp_stop() -> i32 {
    use edamame_core::api::api_agentic::rpc_mcp_stop_server;

    match rpc_mcp_stop_server(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("[OK] MCP server stopped");
                0
            } else {
                eprintln!(
                    "Failed to stop MCP server: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error stopping MCP server: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_mcp_status() -> i32 {
    use edamame_core::api::api_agentic::rpc_mcp_get_server_status;

    match rpc_mcp_get_server_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["running"].as_bool().unwrap_or(false) {
                println!("[OK] MCP server is running");
                println!("   Port: {}", json["port"]);
                println!("   URL: {}", json["url"].as_str().unwrap_or(""));
            } else {
                println!("MCP server is not running");
            }
            0
        }
        Err(e) => {
            eprintln!("Error querying MCP server status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_summary() -> i32 {
    let summary = match rpc_agentic_get_summary(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(summary) => summary,
        Err(e) => {
            eprintln!("Error querying agentic summary: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    println!("================================================================");
    println!("                    AGENTIC STATUS SUMMARY                      ");
    println!("================================================================");

    // LLM Provider
    println!("\n[LLM Provider]");
    println!("  Provider: {}", summary.provider);
    // For internal provider, model is managed by EDAMAME backend
    let model_display = if summary.model.is_empty() {
        if summary.provider == "internal" {
            "managed by backend"
        } else {
            "default"
        }
    } else {
        &summary.model
    };
    println!("  Model: {}", model_display);
    println!(
        "  API Key: {}",
        if summary.has_api_key {
            "configured"
        } else {
            "not set"
        }
    );
    println!("  Tested: {}", if summary.tested { "yes" } else { "no" });

    // Auto Processing
    println!("\n[Auto Processing]");
    println!(
        "  Enabled: {}",
        if summary.auto_processing_enabled {
            "yes"
        } else {
            "no"
        }
    );
    println!("  Mode: {}", summary.auto_processing_mode);
    println!("  Interval: {}s", summary.auto_processing_interval_secs);
    if let Some(ref last_run) = summary.auto_processing_last_run {
        println!("  Last Run: {}", last_run);
    }
    if let Some(ref next_run) = summary.auto_processing_next_run {
        println!("  Next Run: {}", next_run);
    }

    // Subscription
    println!("\n[Subscription]");
    println!("  Plan: {}", summary.subscription_plan);
    println!("  Usage: {:.1}%", summary.subscription_usage * 100.0);

    // Todos
    println!("\n[Security Todos] Total: {}", summary.todo_counts.total);
    if summary.todo_counts.total > 0 {
        if summary.todo_counts.threats > 0 {
            println!("  Threats: {}", summary.todo_counts.threats);
        }
        if summary.todo_counts.policies > 0 {
            println!("  Policies: {}", summary.todo_counts.policies);
        }
        if summary.todo_counts.network_ports > 0 {
            println!("  Network Ports: {}", summary.todo_counts.network_ports);
        }
        if summary.todo_counts.network_sessions > 0 {
            println!(
                "  Network Sessions: {}",
                summary.todo_counts.network_sessions
            );
        }
        if summary.todo_counts.pwned_breaches > 0 {
            println!("  Pwned Breaches: {}", summary.todo_counts.pwned_breaches);
        }
        if summary.todo_counts.configure > 0 {
            println!("  Configuration: {}", summary.todo_counts.configure);
        }
    }

    // Actions
    println!("\n[Action History] Total: {}", summary.action_counts.total);
    if summary.action_counts.total > 0 {
        if summary.action_counts.pending > 0 {
            println!("  Pending: {}", summary.action_counts.pending);
        }
        if summary.action_counts.executed > 0 {
            println!("  Executed: {}", summary.action_counts.executed);
        }
        if summary.action_counts.escalated > 0 {
            println!("  Escalated: {}", summary.action_counts.escalated);
        }
        if summary.action_counts.failed > 0 {
            println!("  Failed: {}", summary.action_counts.failed);
        }
        if summary.action_counts.undone > 0 {
            println!("  Undone: {}", summary.action_counts.undone);
        }
    }

    // Recent Actions
    if !summary.recent_actions.is_empty() {
        println!("\n[Recent Actions] Last {}:", summary.recent_actions.len());
        for action in &summary.recent_actions {
            let status = if action.success { "OK" } else { "FAIL" };
            println!(
                "  [{}] {} - {} [{}]",
                status, action.action_type, action.result_status, action.timestamp
            );
        }
    }

    // Token Usage
    println!("\n[Token Usage]");
    println!(
        "  Last Hour: {} in / {} out",
        summary.tokens_last_hour_input, summary.tokens_last_hour_output
    );
    println!(
        "  Last 24h: {} in / {} out",
        summary.tokens_last_24h_input, summary.tokens_last_24h_output
    );

    // Slack
    println!("\n[Slack Integration]");
    println!(
        "  Configured: {}",
        if summary.slack_configured {
            "yes"
        } else {
            "no"
        }
    );
    if summary.slack_configured {
        println!("  Actions Channel: {}", summary.slack_actions_channel);
        println!(
            "  Escalations Channel: {}",
            summary.slack_escalations_channel
        );
    }

    // Status
    println!("\n[Status]");
    println!("  Success Count: {}", summary.success_count);
    println!("  Failure Count: {}", summary.failure_count);
    if !summary.last_success_time.is_empty() {
        println!("  Last Success: {}", summary.last_success_time);
    }
    if summary.error_code != "None" {
        println!(
            "  Last Error: {} - {}",
            summary.error_code, summary.error_reason
        );
    }

    println!();
    0
}

fn format_agentic_mode(mode: i32) -> &'static str {
    match mode {
        0 => "disabled",
        1 => "analyze",
        2 => "auto",
        _ => "unknown",
    }
}

pub fn background_agentic_start(mode: &str, interval_secs: u64) -> i32 {
    if interval_secs == 0 {
        eprintln!("Invalid interval: must be >= 1 second");
        return ERROR_CODE_PARAM;
    }

    let confirmation_level = match mode {
        "auto" => 0,
        "analyze" => 1,
        _ => {
            eprintln!("Invalid mode '{}': expected 'auto' or 'analyze'", mode);
            return ERROR_CODE_PARAM;
        }
    };

    match rpc_agentic_set_auto_processing(
        true,
        interval_secs,
        confirmation_level,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(true) => {
            println!(
                "AI assistant loop started (mode={}, interval={}s).",
                mode, interval_secs
            );
            0
        }
        Ok(false) => {
            eprintln!("Failed to start AI assistant loop");
            ERROR_CODE_SERVER_ERROR
        }
        Err(e) => {
            eprintln!("Error starting AI assistant loop: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_stop() -> i32 {
    let (interval_secs, confirmation_level) = match rpc_agentic_get_auto_processing_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            let interval = if status.interval_secs == 0 {
                3600
            } else {
                status.interval_secs
            };
            let level = if status.mode == 2 { 0 } else { 1 };
            (interval, level)
        }
        Err(_) => (3600, 1),
    };

    match rpc_agentic_set_auto_processing(
        false,
        interval_secs,
        confirmation_level,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(true) => {
            println!("AI assistant loop stopped.");
            0
        }
        Ok(false) => {
            eprintln!("Failed to stop AI assistant loop");
            ERROR_CODE_SERVER_ERROR
        }
        Err(e) => {
            eprintln!("Error stopping AI assistant loop: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_status() -> i32 {
    match rpc_agentic_get_auto_processing_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            println!("AI assistant loop:");
            println!("  - Enabled: {}", if status.enabled { "yes" } else { "no" });
            println!("  - Mode: {}", format_agentic_mode(status.mode));
            println!("  - Interval: {}s", status.interval_secs);
            println!(
                "  - Timer registered: {}",
                if status.timer_registered { "yes" } else { "no" }
            );
            if let Some(last_run) = status.last_run {
                println!("  - Last run: {}", last_run);
            }
            if let Some(next_run) = status.next_run {
                println!("  - Next run: {}", next_run);
            }
            0
        }
        Err(e) => {
            eprintln!("Error getting AI assistant loop status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

fn print_json_pretty(raw_json: &str, context: &str) -> i32 {
    let json_value: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("Error parsing {} JSON: {}", context, e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    match serde_json::to_string_pretty(&json_value) {
        Ok(pretty_json) => {
            println!("{}", pretty_json);
            0
        }
        Err(e) => {
            eprintln!("Error formatting {} JSON: {}", context, e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_upsert_model(window_json: String) -> i32 {
    match rpc_upsert_behavioral_model(
        window_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing upsert result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("Behavioral model upserted.");
                0
            } else {
                eprintln!(
                    "Failed to upsert behavioral model: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error upserting behavioral model: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_get_model() -> i32 {
    match rpc_get_behavioral_model(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_json_pretty(&result, "behavioral model"),
        Err(e) => {
            eprintln!("Error getting behavioral model: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_clear_model() -> i32 {
    match rpc_clear_behavioral_model(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            println!("Behavioral model cleared.");
            0
        }
        Err(e) => {
            eprintln!("Error clearing behavioral model: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_start(interval_secs: u64) -> i32 {
    match rpc_start_divergence_engine(
        true,
        interval_secs,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing start result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("Divergence engine started (interval={}s).", interval_secs);
                0
            } else {
                eprintln!(
                    "Failed to start divergence engine: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error starting divergence engine: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_stop() -> i32 {
    match rpc_start_divergence_engine(
        false,
        0,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing stop result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("Divergence engine stopped.");
                0
            } else {
                eprintln!(
                    "Failed to stop divergence engine: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error stopping divergence engine: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_status() -> i32 {
    match rpc_get_divergence_engine_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_json_pretty(&result, "divergence status"),
        Err(e) => {
            eprintln!("Error getting divergence status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_get_verdict() -> i32 {
    match rpc_get_divergence_verdict(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_json_pretty(&result, "divergence verdict"),
        Err(e) => {
            eprintln!("Error getting divergence verdict: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_get_history(limit: usize) -> i32 {
    match rpc_get_divergence_history(
        limit,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_json_pretty(&result, "divergence history"),
        Err(e) => {
            eprintln!("Error getting divergence history: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_dismiss(finding_key: String) -> i32 {
    if finding_key.trim().is_empty() {
        eprintln!("Finding key cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_dismiss_divergence_evidence(
        finding_key.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing dismiss result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                println!("Divergence evidence dismissed.");
                0
            } else {
                eprintln!(
                    "Failed to dismiss divergence evidence: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error dismissing divergence evidence: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_undismiss(finding_key: String) -> i32 {
    if finding_key.trim().is_empty() {
        eprintln!("Finding key cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_undismiss_divergence_evidence(
        finding_key.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing undismiss result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                println!("Divergence evidence restored.");
                0
            } else {
                eprintln!(
                    "Failed to restore divergence evidence: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error restoring divergence evidence: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_divergence_reset_suppressions() -> i32 {
    match rpc_reset_divergence_suppressions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing reset result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                println!("Divergence suppressions reset.");
                0
            } else {
                eprintln!(
                    "Failed to reset divergence suppressions: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error resetting divergence suppressions: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ============================================================================
// Vulnerability Detector (model-independent heuristic checks)
// ============================================================================

pub fn background_vulnerability_start(interval_secs: u64) -> i32 {
    match rpc_start_vulnerability_detector(
        true,
        interval_secs,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing start result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!(
                    "Vulnerability detector started (interval={}s).",
                    interval_secs
                );
                0
            } else {
                eprintln!(
                    "Failed to start vulnerability detector: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error starting vulnerability detector: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_vulnerability_stop() -> i32 {
    match rpc_start_vulnerability_detector(
        false,
        0,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing stop result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            if json["success"].as_bool().unwrap_or(false) {
                println!("Vulnerability detector stopped.");
                0
            } else {
                eprintln!(
                    "Failed to stop vulnerability detector: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error stopping vulnerability detector: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Dump active runtime vulnerability findings as JSON.
///
/// Calls the `get_vulnerability_findings` RPC on the running daemon and
/// pretty-prints the report (which includes per-finding `finding_key`,
/// `check`, `severity`, `description`, `process_*`, `destination_*`,
/// `open_files`, and `detection_basis`). When `--active-only` is set,
/// the output is filtered to non-dismissed findings only.
///
/// Exit codes:
///   0 -- printed report (zero or more findings)
///   ERROR_CODE_SERVER_ERROR -- RPC failed or response was unparseable
pub fn background_vulnerability_findings(active_only: bool) -> i32 {
    match rpc_get_vulnerability_findings(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            // The RPC returns a JSON-encoded string (the inner value is
            // already a JSON object with `findings` etc.). Parse it once
            // so we can pretty-print and optionally filter.
            let inner: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "Error parsing vulnerability findings JSON: {} -- raw: {}",
                        e, result
                    );
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            let mut report = inner;
            if active_only {
                if let Some(findings) = report.get_mut("findings").and_then(|f| f.as_array_mut()) {
                    findings.retain(|finding| {
                        !finding
                            .get("dismissed")
                            .and_then(|d| d.as_bool())
                            .unwrap_or(false)
                    });
                }
            }

            match serde_json::to_string_pretty(&report) {
                Ok(pretty) => println!("{}", pretty),
                Err(e) => {
                    eprintln!("Error formatting vulnerability findings JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("Error getting vulnerability findings: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_vulnerability_status(fail_on_findings: bool) -> i32 {
    match rpc_get_vulnerability_detector_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json_value: serde_json::Value = match serde_json::from_str(&result) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("Error parsing vulnerability detector status JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };

            match serde_json::to_string_pretty(&json_value) {
                Ok(pretty_json) => println!("{}", pretty_json),
                Err(e) => {
                    eprintln!("Error formatting vulnerability detector status JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            }

            if fail_on_findings {
                // Prefer `active_alertable_findings` (HIGH/CRITICAL only)
                // when the daemon exposes it. LOW severity findings
                // (e.g. ambient `spawned_from_tmp` signals from CI
                // bootstrappers like `rustup-init` or `cargo install`)
                // appear in the dashboard for visibility but should not
                // by themselves fail the gate. Older daemons that do
                // not yet emit this field fall back to the raw
                // `active_findings` total so the gate keeps working
                // during a rolling upgrade.
                let alertable_findings = json_value
                    .get("active_alertable_findings")
                    .and_then(|value| value.as_u64());
                let active_findings = alertable_findings.unwrap_or_else(|| {
                    json_value
                        .get("active_findings")
                        .and_then(|value| value.as_u64())
                        .unwrap_or(0)
                });
                if active_findings > 0 {
                    eprintln!(
                        "Active vulnerability findings detected: {} ({})",
                        active_findings,
                        if alertable_findings.is_some() {
                            "HIGH/CRITICAL severity"
                        } else {
                            "all severities (legacy daemon)"
                        }
                    );
                    return ERROR_CODE_MISMATCH;
                }
            }

            0
        }
        Err(e) => {
            eprintln!("Error getting vulnerability detector status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Dump the `VulnerabilityDebugTrace` JSON for a past attack pattern report.
///
/// Calls `get_vulnerability_debug_trace(report_id)` on the running daemon and
/// pretty-prints the trace (`input_slices`, `deterministic_findings`,
/// `llm_decision`, etc.). This is the canonical FP corpus capture input:
/// the trace can be replayed deterministically through the detector to
/// validate suppression-hook changes against historical false positives
/// without re-running the original live scenario.
///
/// When `report_id` is `None`, resolves the latest in-memory report by first
/// calling `get_vulnerability_findings` and extracting its `report_id`. This
/// is the `--latest` CLI path.
///
/// Exit codes:
///   0                       -- printed trace JSON (or `{"trace": null}` when no trace is stored)
///   ERROR_CODE_PARAM        -- daemon has no current report to resolve `--latest` against
///   ERROR_CODE_SERVER_ERROR -- RPC failed or response was unparseable
pub fn background_vulnerability_debug_trace(report_id: Option<String>) -> i32 {
    let resolved_id = match report_id {
        Some(id) if !id.trim().is_empty() => id.trim().to_string(),
        _ => {
            // Resolve latest report_id from get_vulnerability_findings.
            match rpc_get_vulnerability_findings(
                &EDAMAME_CA_PEM,
                &EDAMAME_CLIENT_PEM,
                &EDAMAME_CLIENT_KEY,
                &EDAMAME_TARGET,
            ) {
                Ok(result) => {
                    let inner: serde_json::Value = match serde_json::from_str(&result) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!(
                                "Error parsing vulnerability findings JSON: {} -- raw: {}",
                                e, result
                            );
                            return ERROR_CODE_SERVER_ERROR;
                        }
                    };
                    match inner.get("report_id").and_then(|v| v.as_str()) {
                        Some(id) if !id.is_empty() => id.to_string(),
                        _ => {
                            eprintln!(
                                "No current vulnerability report available; daemon may not have run a detector tick yet."
                            );
                            return ERROR_CODE_PARAM;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error resolving latest report_id: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            }
        }
    };

    match rpc_get_vulnerability_debug_trace(
        resolved_id.clone(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let trace: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "Error parsing vulnerability debug trace JSON: {} -- raw: {}",
                        e, result
                    );
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            match serde_json::to_string_pretty(&trace) {
                Ok(pretty) => println!("{}", pretty),
                Err(e) => {
                    eprintln!("Error formatting vulnerability debug trace JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            }
            0
        }
        Err(e) => {
            eprintln!(
                "Error getting vulnerability debug trace (report_id={}): {}",
                resolved_id, e
            );
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_vulnerability_dismiss(finding_key: String) -> i32 {
    if finding_key.trim().is_empty() {
        eprintln!("Finding key cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_dismiss_vulnerability_finding(
        finding_key.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing dismiss result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                if json["changed"].as_bool().unwrap_or(true) {
                    println!("Vulnerability finding dismissed.");
                } else {
                    println!("No matching finding found or already dismissed.");
                }
                0
            } else {
                eprintln!(
                    "Failed to dismiss vulnerability finding: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error dismissing vulnerability finding: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_vulnerability_undismiss(finding_key: String) -> i32 {
    if finding_key.trim().is_empty() {
        eprintln!("Finding key cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_undismiss_vulnerability_finding(
        finding_key.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing undismiss result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                if json["changed"].as_bool().unwrap_or(true) {
                    println!("Vulnerability finding restored.");
                } else {
                    println!("No matching dismissed finding found or already restored.");
                }
                0
            } else {
                eprintln!(
                    "Failed to restore vulnerability finding: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error restoring vulnerability finding: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_vulnerability_reset_suppressions() -> i32 {
    match rpc_reset_vulnerability_suppressions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing reset result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                if json["changed"].as_bool().unwrap_or(true) {
                    println!("Vulnerability suppressions reset.");
                } else {
                    println!("No dismissed findings to reset.");
                }
                0
            } else {
                eprintln!(
                    "Failed to reset vulnerability suppressions: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error resetting vulnerability suppressions: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_clear_vulnerability_history() -> i32 {
    match rpc_clear_vulnerability_history(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            println!("Vulnerability history cleared.");
            0
        }
        Err(e) => {
            eprintln!("Error clearing vulnerability history: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_dismiss_with_scope(request_json: String) -> i32 {
    if request_json.trim().is_empty() {
        eprintln!("Dismiss-with-scope request JSON cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_agentic_dismiss_with_scope(
        request_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing dismiss-with-scope result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                println!(
                    "Dismissal rule created: {}",
                    json["rule_id"].as_str().unwrap_or("unknown")
                );
                0
            } else {
                eprintln!(
                    "Failed to create dismissal rule: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error creating dismissal rule: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_list_dismissal_rules(domain: Option<String>) -> i32 {
    let domain = domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    match rpc_agentic_list_dismissal_rules(
        domain.to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing dismissal rules JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if !json["success"].as_bool().unwrap_or(false) {
                eprintln!(
                    "Failed to list dismissal rules: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                return ERROR_CODE_SERVER_ERROR;
            }
            match serde_json::to_string_pretty(&json) {
                Ok(pretty) => println!("{}", pretty),
                Err(e) => {
                    eprintln!("Error formatting dismissal rules JSON: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("Error listing dismissal rules: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agentic_remove_dismissal_rule(rule_id: String) -> i32 {
    if rule_id.trim().is_empty() {
        eprintln!("Dismissal rule id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_agentic_remove_dismissal_rule(
        rule_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => {
            let json: serde_json::Value = match serde_json::from_str(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing remove-rule result: {}", e);
                    return ERROR_CODE_SERVER_ERROR;
                }
            };
            if json["success"].as_bool().unwrap_or(false) {
                if json["removed"].as_bool().unwrap_or(true) {
                    println!("Dismissal rule removed.");
                } else {
                    println!("No matching dismissal rule found.");
                }
                0
            } else {
                eprintln!(
                    "Failed to remove dismissal rule: {}",
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error removing dismissal rule: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ===========================================================================
// Agent Visibility + Transcript Observer (MVP)
//
// Reads return JSON strings (same convention as vulnerability findings); we
// parse + pretty-print. Mutators return a {"success": bool, ...} envelope.
// See edamame_core/VISIBILITYIMPROVEMENTS.md.
// ===========================================================================

/// Pretty-print a JSON string returned by a visibility/observer read RPC.
fn print_visibility_json(raw: &str, label: &str) -> i32 {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(pretty) => {
                println!("{}", pretty);
                0
            }
            Err(e) => {
                eprintln!("Error formatting {} JSON: {}", label, e);
                ERROR_CODE_SERVER_ERROR
            }
        },
        Err(e) => {
            eprintln!("Error parsing {} JSON: {} -- raw: {}", label, e, raw);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Validate + pretty-print a `{"success": bool, ...}` envelope returned by a
/// visibility/observer mutator RPC. Exit code reflects `success`.
fn print_visibility_envelope(raw: &str, label: &str) -> i32 {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(json) => {
            if json["success"].as_bool().unwrap_or(false) {
                match serde_json::to_string_pretty(&json) {
                    Ok(pretty) => println!("{}", pretty),
                    Err(_) => println!("{}", raw),
                }
                0
            } else {
                eprintln!(
                    "{} failed: {}",
                    label,
                    json["error"].as_str().unwrap_or("Unknown")
                );
                ERROR_CODE_SERVER_ERROR
            }
        }
        Err(e) => {
            eprintln!("Error parsing {} result: {} -- raw: {}", label, e, raw);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Dump the agent fleet overview rollup (spend, sessions, errors, waste,
/// top agents) as pretty-printed JSON.
pub fn background_agent_fleet_overview(window_minutes: u64) -> i32 {
    match rpc_get_agent_fleet_overview(
        window_minutes,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "agent fleet overview"),
        Err(e) => {
            eprintln!("Error getting agent fleet overview: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Dump deterministic tool-failure clusters (tool x error class) as
/// pretty-printed JSON. `agent_type` empty means all agents.
pub fn background_agent_failure_clusters(window_minutes: u64, agent_type: String) -> i32 {
    match rpc_get_agent_failure_clusters(
        window_minutes,
        agent_type,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "agent failure clusters"),
        Err(e) => {
            eprintln!("Error getting agent failure clusters: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Dump operator-set per-agent daily budgets joined with today's actuals
/// as pretty-printed JSON.
pub fn background_agent_budgets() -> i32 {
    match rpc_get_agent_budgets(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "agent budgets"),
        Err(e) => {
            eprintln!("Error getting agent budgets: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Set or clear the daily budget for one agent type (operator-only). A cap
/// of 0 clears that axis; when both axes are cleared the entry is removed.
pub fn background_set_agent_budget(
    agent_type: String,
    daily_cost_usd_cap: f64,
    daily_token_cap: u64,
) -> i32 {
    match rpc_set_agent_budget(
        agent_type,
        daily_cost_usd_cap,
        daily_token_cap,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Set agent budget"),
        Err(e) => {
            eprintln!("Error setting agent budget: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agent_visibility_refresh() -> i32 {
    match rpc_refresh_agent_visibility(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Agent visibility refresh"),
        Err(e) => {
            eprintln!("Error refreshing agent visibility: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_visibility_summary() -> i32 {
    match rpc_get_visibility_summary(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(pretty) => {
                println!("{}", pretty);
                0
            }
            Err(e) => {
                eprintln!("Error formatting visibility summary: {}", e);
                ERROR_CODE_SERVER_ERROR
            }
        },
        Err(e) => {
            eprintln!("Error getting visibility summary: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_mcp_inventory() -> i32 {
    match rpc_get_mcp_inventory(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "MCP inventory"),
        Err(e) => {
            eprintln!("Error getting MCP inventory: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_mcp_findings() -> i32 {
    match rpc_get_mcp_findings(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "MCP findings"),
        Err(e) => {
            eprintln!("Error getting MCP findings: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agent_component_inventories() -> i32 {
    match rpc_get_agent_component_inventories(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Agent component inventories"),
        Err(e) => {
            eprintln!("Error getting agent component inventories: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_capability_graph() -> i32 {
    match rpc_get_capability_graph(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Capability graph"),
        Err(e) => {
            eprintln!("Error getting capability graph: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_recursion_risk() -> i32 {
    match rpc_get_recursion_risk(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Recursion risk"),
        Err(e) => {
            eprintln!("Error getting recursion risk: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agent_inventory() -> i32 {
    match rpc_get_agent_inventory(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Agent inventory"),
        Err(e) => {
            eprintln!("Error getting agent inventory: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_graph_reachability() -> i32 {
    match rpc_get_graph_reachability(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Graph reachability"),
        Err(e) => {
            eprintln!("Error getting graph reachability: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_effective_capabilities() -> i32 {
    match rpc_get_effective_capabilities(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Effective capabilities"),
        Err(e) => {
            eprintln!("Error getting effective capabilities: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_metrics_history(family: String, granularity: String, range_minutes: u64) -> i32 {
    match rpc_get_metrics_history(
        family,
        granularity,
        range_minutes,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Metrics history"),
        Err(e) => {
            eprintln!("Error getting metrics history: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_augmentation_report(window_minutes: u64) -> i32 {
    match rpc_get_self_augmentation_report(
        window_minutes,
        String::new(),
        String::new(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Self-augmentation report"),
        Err(e) => {
            eprintln!("Error getting self-augmentation report: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_approve_agent(agent_type: String) -> i32 {
    if agent_type.trim().is_empty() {
        eprintln!("Agent type cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_approve_agent(
        agent_type.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Approve agent"),
        Err(e) => {
            eprintln!("Error approving agent: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_revoke_agent_approval(agent_type: String) -> i32 {
    if agent_type.trim().is_empty() {
        eprintln!("Agent type cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_revoke_agent_approval(
        agent_type.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Revoke agent approval"),
        Err(e) => {
            eprintln!("Error revoking agent approval: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_mcp_endpoints() -> i32 {
    match rpc_get_mcp_endpoints(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "MCP endpoints"),
        Err(e) => {
            eprintln!("Error getting MCP endpoints: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_visibility_capture_tier() -> i32 {
    match rpc_get_visibility_capture_tier(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(tier) => match serde_json::to_string_pretty(&tier) {
            Ok(pretty) => {
                println!("{}", pretty);
                0
            }
            Err(e) => {
                eprintln!("Error formatting visibility capture tier: {}", e);
                ERROR_CODE_SERVER_ERROR
            }
        },
        Err(e) => {
            eprintln!("Error getting visibility capture tier: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_set_visibility_capture_tier(tier: String) -> i32 {
    if tier.trim().is_empty() {
        eprintln!("Capture tier cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_set_visibility_capture_tier(
        tier.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Set visibility capture tier"),
        Err(e) => {
            eprintln!("Error setting visibility capture tier: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-5 Flight Recorder
// ---------------------------------------------------------------------------

pub fn background_refresh_run_provenance() -> i32 {
    match rpc_refresh_run_provenance(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh run provenance"),
        Err(e) => {
            eprintln!("Error refreshing run provenance: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_list_recent_runs() -> i32 {
    match rpc_list_recent_runs(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Recent runs"),
        Err(e) => {
            eprintln!("Error listing recent runs: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_run_provenance(run_id: String) -> i32 {
    if run_id.trim().is_empty() {
        eprintln!("Run id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_get_run_provenance(
        run_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Run provenance"),
        Err(e) => {
            eprintln!("Error getting run provenance: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_explain_run_event(run_id: String, event_id: String) -> i32 {
    if run_id.trim().is_empty() || event_id.trim().is_empty() {
        eprintln!("Run id and event id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_explain_run_event(
        run_id.trim().to_string(),
        event_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Run event explanation"),
        Err(e) => {
            eprintln!("Error explaining run event: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-6 Drift Timeline
// ---------------------------------------------------------------------------

pub fn background_refresh_agent_drift() -> i32 {
    match rpc_refresh_agent_drift(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh agent drift"),
        Err(e) => {
            eprintln!("Error refreshing agent drift: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agent_drift() -> i32 {
    match rpc_get_agent_drift(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Agent drift"),
        Err(e) => {
            eprintln!("Error getting agent drift: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_agent_drift_timeline(agent_key: String) -> i32 {
    if agent_key.trim().is_empty() {
        eprintln!("Agent key cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_get_agent_drift_timeline(
        agent_key.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Agent drift timeline"),
        Err(e) => {
            eprintln!("Error getting agent drift timeline: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_explain_agent_drift(agent_key: String, event_id: String) -> i32 {
    if agent_key.trim().is_empty() || event_id.trim().is_empty() {
        eprintln!("Agent key and event id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_explain_agent_drift(
        agent_key.trim().to_string(),
        event_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Agent drift explanation"),
        Err(e) => {
            eprintln!("Error explaining agent drift: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-7 Data-Flow Map
// ---------------------------------------------------------------------------

pub fn background_refresh_dataflow_maps() -> i32 {
    match rpc_refresh_dataflow_maps(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh data-flow maps"),
        Err(e) => {
            eprintln!("Error refreshing data-flow maps: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_dataflow_maps() -> i32 {
    match rpc_get_dataflow_maps(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Data-flow maps"),
        Err(e) => {
            eprintln!("Error getting data-flow maps: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_dataflow_map(agent_type: String) -> i32 {
    if agent_type.trim().is_empty() {
        eprintln!("Agent type cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_get_dataflow_map(
        agent_type.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Data-flow map"),
        Err(e) => {
            eprintln!("Error getting data-flow map: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-8 Memory & RAG inventory
// ---------------------------------------------------------------------------

pub fn background_refresh_memory_inventory() -> i32 {
    match rpc_refresh_memory_inventory(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh memory inventory"),
        Err(e) => {
            eprintln!("Error refreshing memory inventory: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_memory_inventory() -> i32 {
    match rpc_get_memory_inventory(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Memory inventory"),
        Err(e) => {
            eprintln!("Error getting memory inventory: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-9 A2A mapping
// ---------------------------------------------------------------------------

pub fn background_refresh_a2a_graph() -> i32 {
    match rpc_refresh_a2a_graph(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh A2A graph"),
        Err(e) => {
            eprintln!("Error refreshing A2A graph: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_a2a_graph() -> i32 {
    match rpc_get_a2a_graph(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "A2A graph"),
        Err(e) => {
            eprintln!("Error getting A2A graph: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-10 Tool-Call Firewall
// ---------------------------------------------------------------------------

pub fn background_firewall_status() -> i32 {
    match rpc_get_firewall_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Firewall status"),
        Err(e) => {
            eprintln!("Error getting firewall status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_firewall_evaluations() -> i32 {
    match rpc_get_firewall_evaluations(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Firewall evaluations"),
        Err(e) => {
            eprintln!("Error getting firewall evaluations: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_refresh_firewall_evaluations() -> i32 {
    match rpc_refresh_firewall_evaluations(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh firewall evaluations"),
        Err(e) => {
            eprintln!("Error refreshing firewall evaluations: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_set_firewall_mode(mode: String) -> i32 {
    if mode.trim().is_empty() {
        eprintln!("Firewall mode cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_set_firewall_mode(
        mode.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Set firewall mode"),
        Err(e) => {
            eprintln!("Error setting firewall mode: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-11 ADR Response & Case Export
// ---------------------------------------------------------------------------

pub fn background_response_action_catalog() -> i32 {
    match rpc_get_response_action_catalog(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Response action catalog"),
        Err(e) => {
            eprintln!("Error getting response action catalog: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_response_action_history() -> i32 {
    match rpc_get_response_action_history(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Response action history"),
        Err(e) => {
            eprintln!("Error getting response action history: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_request_response_action(
    kind: String,
    target_ref: String,
    reason: String,
    simulated: bool,
) -> i32 {
    if kind.trim().is_empty() || target_ref.trim().is_empty() {
        eprintln!("Response action kind and target_ref cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_request_response_action(
        kind.trim().to_string(),
        target_ref.trim().to_string(),
        reason,
        simulated,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Request response action"),
        Err(e) => {
            eprintln!("Error requesting response action: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_undo_response_action(action_id: String) -> i32 {
    if action_id.trim().is_empty() {
        eprintln!("Action id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_undo_response_action(
        action_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Undo response action"),
        Err(e) => {
            eprintln!("Error undoing response action: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_export_visibility_case(run_id: String) -> i32 {
    if run_id.trim().is_empty() {
        eprintln!("Run id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_export_visibility_case(
        run_id.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Visibility case export"),
        Err(e) => {
            eprintln!("Error exporting visibility case: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// INC-13 Governance (policy packs, attestation, cross-zone)
// ---------------------------------------------------------------------------

pub fn background_policy_pack() -> i32 {
    match rpc_get_policy_pack(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Policy pack"),
        Err(e) => {
            eprintln!("Error getting policy pack: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_set_policy_pack(pack: String) -> i32 {
    if pack.trim().is_empty() {
        eprintln!("Policy pack argument cannot be empty");
        return ERROR_CODE_PARAM;
    }
    // The argument is either a path to a JSON file or inline JSON. If it points
    // at a readable file, load its contents; otherwise treat it as literal JSON.
    let pack_json = if std::path::Path::new(pack.trim()).is_file() {
        match std::fs::read_to_string(pack.trim()) {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!("Error reading policy pack file '{}': {}", pack.trim(), e);
                return ERROR_CODE_PARAM;
            }
        }
    } else {
        pack
    };
    match rpc_set_policy_pack(
        pack_json,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Set policy pack"),
        Err(e) => {
            eprintln!("Error setting policy pack: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_refresh_policy_evaluation() -> i32 {
    match rpc_refresh_policy_evaluation(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Refresh policy evaluation"),
        Err(e) => {
            eprintln!("Error refreshing policy evaluation: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_policy_evaluation() -> i32 {
    match rpc_get_policy_evaluation(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Policy evaluation"),
        Err(e) => {
            eprintln!("Error getting policy evaluation: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_attest_policy_evaluation() -> i32 {
    match rpc_attest_policy_evaluation(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Attest policy evaluation"),
        Err(e) => {
            eprintln!("Error attesting policy evaluation: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_policy_attestations() -> i32 {
    match rpc_get_policy_attestations(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Policy attestations"),
        Err(e) => {
            eprintln!("Error getting policy attestations: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_zone_promotions() -> i32 {
    match rpc_get_zone_promotions(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Zone promotions"),
        Err(e) => {
            eprintln!("Error getting zone promotions: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_request_zone_promotion(
    agent_type: String,
    target_zone: String,
    reason: String,
) -> i32 {
    if agent_type.trim().is_empty() || target_zone.trim().is_empty() {
        eprintln!("Agent type and target zone cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_request_zone_promotion(
        agent_type.trim().to_string(),
        target_zone.trim().to_string(),
        reason,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Request zone promotion"),
        Err(e) => {
            eprintln!("Error requesting zone promotion: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_decide_zone_promotion(promotion_id: String, decision: String) -> i32 {
    if promotion_id.trim().is_empty() {
        eprintln!("Promotion id cannot be empty");
        return ERROR_CODE_PARAM;
    }
    let approve = match decision.trim().to_ascii_lowercase().as_str() {
        "approve" | "approved" | "accept" | "yes" | "true" => true,
        "reject" | "rejected" | "deny" | "denied" | "no" | "false" => false,
        other => {
            eprintln!("Unknown decision '{}' (expected approve | reject)", other);
            return ERROR_CODE_PARAM;
        }
    };
    match rpc_decide_zone_promotion(
        promotion_id.trim().to_string(),
        approve,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Decide zone promotion"),
        Err(e) => {
            eprintln!("Error deciding zone promotion: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_observer_status() -> i32 {
    match rpc_get_transcript_observer_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_json(&result, "Transcript observer status"),
        Err(e) => {
            eprintln!("Error getting transcript observer status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_observer_set_enabled(agent_type: String, enabled: bool) -> i32 {
    if agent_type.trim().is_empty() {
        eprintln!("Agent type cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_set_transcript_observer_enabled(
        agent_type.trim().to_string(),
        enabled,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(
            &result,
            if enabled {
                "Observer enable"
            } else {
                "Observer disable"
            },
        ),
        Err(e) => {
            eprintln!("Error setting transcript observer state: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_observer_tick(agent_type: String) -> i32 {
    if agent_type.trim().is_empty() {
        eprintln!("Agent type cannot be empty");
        return ERROR_CODE_PARAM;
    }
    match rpc_run_transcript_observer_tick_for(
        agent_type.trim().to_string(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(result) => print_visibility_envelope(&result, "Observer tick"),
        Err(e) => {
            eprintln!("Error running transcript observer tick: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

/// Process security todos with AI in background mode
pub fn background_process_agentic(mode: &str) {
    info!(
        "AI Assistant: Starting automated todo processing (mode: {})",
        mode
    );

    // Supported CLI/daemon modes: auto (execute) or analyze (recommendations only)
    let confirmation_level = match mode {
        "auto" => 0,
        "analyze" => 1,
        _ => {
            warn!(
                "AI Assistant: Unsupported mode '{}', valid options are 'auto', 'analyze', or 'disabled'",
                mode
            );
            return;
        }
    };

    let results = agentic_process_todos(confirmation_level);

    if mode == "analyze" {
        info!(
            "AI Assistant: Analyze mode completed – actions recorded for confirmation, no automatic execution performed"
        );
    }

    // Log results
    {
        let total = results.auto_resolved.len()
            + results.requires_confirmation.len()
            + results.escalated.len()
            + results.failed.len();

        if total > 0 {
            info!(
                "AI Assistant: Processed {} todos - {} auto-resolved, {} require confirmation, {} escalated, {} failed",
                total,
                results.auto_resolved.len(),
                results.requires_confirmation.len(),
                results.escalated.len(),
                results.failed.len()
            );

            if !results.requires_confirmation.is_empty() {
                for result in &results.requires_confirmation {
                    info!(
                        "  PENDING {}: todo_id={}, risk_score={:.2}, reasoning={}",
                        result.advice_type,
                        result.todo_id,
                        result.decision.risk_score,
                        result.decision.reasoning
                    );
                }
            }

            // Log escalated items with full details at WARN level for visibility
            if !results.escalated.is_empty() {
                warn!(
                    "AI Assistant: {} escalated todos need manual attention:",
                    results.escalated.len()
                );
                for result in &results.escalated {
                    warn!(
                        "  ESCALATED {}: todo_id={}, risk_score={:.2}, reasoning={}",
                        result.advice_type,
                        result.todo_id,
                        result.decision.risk_score,
                        result.decision.reasoning
                    );
                }
            }

            // Log failures
            if !results.failed.is_empty() {
                error!(
                    "AI Assistant: {} todos failed processing:",
                    results.failed.len()
                );
                for result in &results.failed {
                    error!(
                        "  → {} - {}",
                        result.advice_type,
                        result
                            .error
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string())
                    );
                }
            }
        } else {
            info!("AI Assistant: No todos to process");
        }
    }
}

pub fn background_set_agentic_loop(enabled: bool, interval_secs: u64, mode: &str) -> bool {
    use edamame_core::api::api_agentic::agentic_set_auto_processing;

    let confirmation_level = match mode {
        "auto" => 0,
        "analyze" => 1,
        "disabled" => 1,
        other => {
            warn!(
                "AI Assistant: Unsupported mode '{}' for auto-processing loop",
                other
            );
            return false;
        }
    };

    let success = agentic_set_auto_processing(enabled, interval_secs, confirmation_level);
    if success {
        if enabled {
            info!(
                "AI Assistant: Background loop enabled (interval={}s, mode={})",
                interval_secs, mode
            );
        } else {
            info!("AI Assistant: Background loop disabled");
        }
    } else {
        error!(
            "AI Assistant: Failed to {} background loop",
            if enabled { "enable" } else { "disable" }
        );
    }
    success
}

pub fn background_start_file_monitor(paths: &[String]) -> i32 {
    match rpc_start_file_monitor(
        paths.to_vec(),
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            info!("File monitor started");
            0
        }
        Err(e) => {
            eprintln!("Error starting file monitor: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_stop_file_monitor() -> i32 {
    match rpc_stop_file_monitor(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            info!("File monitor stopped");
            0
        }
        Err(e) => {
            eprintln!("Error stopping file monitor: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_file_monitor_status() -> i32 {
    match rpc_get_file_monitor_status(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&status).unwrap_or_default()
            );
            0
        }
        Err(e) => {
            eprintln!("Error getting file monitor status: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}

pub fn background_get_file_events(fail_on_suspicious: bool) -> i32 {
    let snapshot = match rpc_get_file_events(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!("Error getting file events: {}", e);
            return ERROR_CODE_SERVER_ERROR;
        }
    };

    for event in &snapshot.events {
        let sensitivity = if event.is_sensitive { "sensitive" } else { "" };
        let labels = if event.labels.is_empty() {
            String::new()
        } else {
            format!(" ({})", event.labels.join(", "))
        };
        let process = event
            .process_name
            .as_ref()
            .map(|p| format!(" - correlated: {}", p))
            .unwrap_or_default();

        println!(
            "[{}] {} {}{}{}{}",
            event.timestamp,
            event.event_type,
            event.path,
            labels,
            if !sensitivity.is_empty() {
                format!(" [{}]", sensitivity)
            } else {
                String::new()
            },
            process
        );
    }

    println!(
        "\nTotal events: {}, Sensitive: {}, Monitoring: {}",
        snapshot.event_count,
        snapshot.sensitive_events.len(),
        snapshot.is_monitoring
    );

    if fail_on_suspicious && snapshot.has_suspicious_events {
        eprintln!("Suspicious file events detected");
        return ERROR_CODE_MISMATCH;
    }

    0
}

pub fn background_clear_file_events() -> i32 {
    match rpc_clear_file_events(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(_) => {
            info!("File events cleared");
            0
        }
        Err(e) => {
            eprintln!("Error clearing file events: {}", e);
            ERROR_CODE_SERVER_ERROR
        }
    }
}
