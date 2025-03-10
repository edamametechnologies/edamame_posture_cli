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

pub fn background_get_sessions(local_traffic: bool, zeek_format: bool) -> i32 {
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

    let sessions = if !local_traffic {
        // Filter out local traffic
        filter_global_sessions(sessions.sessions)
    } else {
        sessions.sessions
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
        eprintln!("Some connections failed the whitelist check");
        return ERROR_CODE_MISMATCH;
    } else {
        return 0;
    }
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
        let devices = match rpc_get_lan_devices(
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
