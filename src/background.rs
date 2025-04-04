use crate::base::*;
use crate::EDAMAME_CA_PEM;
use crate::EDAMAME_CLIENT_KEY;
use crate::EDAMAME_CLIENT_PEM;
use crate::EDAMAME_TARGET;
use crate::ERROR_CODE_MISMATCH;
use crate::ERROR_CODE_PARAM;
use crate::ERROR_CODE_SERVER_ERROR;
use crate::ERROR_CODE_TIMEOUT;
use edamame_core::api::api_core::*;
use edamame_core::api::api_lanscan::*;
use edamame_core::api::api_score::*;
use edamame_core::api::api_score_history::*;
use edamame_core::api::api_score_threats::*;
use edamame_core::api::api_trust::*;
use std::thread::sleep;
use std::time::Duration;

pub fn background_get_sessions(
    zeek_format: bool,
    local_traffic: bool,
    check_anomalous: bool,
    check_blacklisted: bool,
) -> i32 {
    let sessions = match rpc_get_lan_sessions(
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

    // Check for anomalous sessions if requested
    if check_anomalous {
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
    if check_blacklisted {
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
                    != edamame_core::api::api_lanscan::WhiteListStateAPI::Conforming
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
    match rpc_get_connection(
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    ) {
        Ok(status) => {
            println!("Connection status:");
            println!("{}", status);
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

pub fn background_wait_for_connection(timeout: u64) -> i32 {
    // Display device and system info
    base_get_device_info();
    base_get_system_info();

    println!("Waiting for score computation and reporting to complete...");
    let mut timeout = timeout;

    let mut last_reported_signature = "".to_string();
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
    };

    // Wait for a non-empty signature or until we time out
    while last_reported_signature.is_empty() && timeout > 0 {
        sleep(Duration::from_secs(5));
        timeout = timeout - 5;

        last_reported_signature = match rpc_get_last_report_signature(
            &EDAMAME_CA_PEM,
            &EDAMAME_CLIENT_PEM,
            &EDAMAME_CLIENT_KEY,
            &EDAMAME_TARGET,
        ) {
            Ok(signature) => signature,
            Err(e) => {
                eprintln!("Error getting last reported signature: {}", e);
                return 1;
            }
        };

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
            last_reported_signature
        );
    }

    if timeout <= 0 {
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

        // Print the connections
        let sessions = match rpc_get_lan_sessions(
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
        format_sessions_log(sessions.sessions);
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

pub fn background_set_custom_blacklists(blacklist_json: String) -> i32 {
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
